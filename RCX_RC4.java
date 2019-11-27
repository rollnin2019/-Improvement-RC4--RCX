import java.util.Random;



public class RCX_RC4 {
	
	static byte[] store = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
            'm', 'n', 'o', 'p', 'q'};
	static String aim_keyString = "5b2ae3b";
	
	static byte[] aim_key = {
			'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e',
	};
	
	
	public static byte[] decry_RCX(byte[] data, String key) {
		// 解密
		if (data == null || key == null) {
			return null;
		}
		
		byte[] rc4Base = RCXBase(data, key);
		//EMoodProtocol.byte2HexString(rc4Base, "rc4解密后的数据");

		return rc4Base;
	}
	
	public static String decry_RCX1(byte[] data, String key) {
		// 解密
		if (data == null || key == null) {
			return null;
		}
		
		
		byte[] rc4Base = RCXBase(data, key);
		//EMoodProtocol.byte2HexString(rc4Base, "rc4解密后的数据");
		
		return asString(rc4Base);
	}

	public static String decry_RCX(String data, String key) {
		// 解密RC4 程序入口
		if (data == null || key == null) {
			return null;
		}
		return new String(RCXBase(HexString2Bytes(data), key));
	}

	
	public static byte[] encry_RCX_byte(String data, String key) {
		// 
		if (data == null || key == null) {
			return null;
		}
		// getBytes() 是Java编程语言中将一个字符串转化为一个字节数组byte[]的方法。
		// String的getBytes()方法是得到一个系统默认的编码格式的字节数组。
		byte b_data[] = data.getBytes();
		//  return byte数组
		return RCXBase(b_data, key);
	}

	public static String encry_RCX_string(String data, String key) {
		// 加密算法入口 参数加密数据跟密钥
		
		if (data == null || key == null) {
			return null;
		}
		
		// toHexString方法:返回得到的加密后的数据  byte数据[]
		// asString   得到String对象
		// encry_RC4_byte  
		return toHexString(asString(encry_RCX_byte(data, key)));
	}

	private static String asString(byte[] buf) {
		
		//  参数是得到的更改后的result byte数组  将其加入StringBuffer对象并以字符串返回
		StringBuffer strbuf = new StringBuffer();
		
		for (int i = 0; i < buf.length; i++) {
			strbuf.append((char) buf[i]);
		}
		return strbuf.toString();
	}

	private static byte[] initKey(String aKey) {
		// 处理状态向量 state
		byte[] b_key = aKey.getBytes();
		byte state[] = new byte[256];
		for (int i = 0; i < 256; i++) {
			state[i] = (byte) i;
			
 		}
		// (1) state = [0 1 2 3 ..... 127  -128 -127 -126 ... -2 -1]
		//  (2) now : state = [0 1 2 3 ..... 127  。。。]
		int index1 = 0;
		int index2 = 0;
		if (b_key == null || b_key.length == 0) {
			return null;
		}
		
		for (int i = 0; i < 256; i++) {
			index2 = ((b_key[index1] & 0xff) + (state[i] & 0xff) + index2) & 0xff;
			
			// 十六进制 0xff = 255 十进制
			
			byte tmp = state[i];
			state[i] = state[index2];
			state[index2] = tmp;	
			//  state[i],state[index2] == state[index2],state[i]
			index1 = (index1 + 1) % b_key.length;
		}
		// 返回[]
		return state;
	}

	private static String toHexString(String s) {
		//  得到的事ASCII符号 转换成十六进数字
			
		String str = "";
		for (int i = 0; i < s.length(); i++) {
			int ch = (int) s.charAt(i);
			// 参数字符串 参数长度循环 参数每一个位置 与255按位与 得到十六进制Str格式s4
			String s4 = Integer.toHexString(ch & 0xFF);
			if (s4.length() == 1) {
				s4 = '0' + s4;
			}
			str = str + s4;
		}
	
		return str;		// 0x表示十六进制
	}

	private static byte[] HexString2Bytes(String src) {
		
		int size = src.length();
		byte[] ret = new byte[size / 2];
		byte[] tmp = src.getBytes();
		for (int i = 0; i < size / 2; i++) {
			ret[i] = uniteBytes(tmp[i * 2], tmp[i * 2 + 1]);
		}
		
		return ret;
	}

	private static byte uniteBytes(byte src0, byte src1) {
		char _b0 = (char) Byte.decode("0x" + new String(new byte[] { src0 })).byteValue();
		//  ??
		
		// _b0 乘以 2的4次方 取char
		_b0 = (char) (_b0 << 4);
		char _b1 = (char) Byte.decode("0x" + new String(new byte[] { src1 })).byteValue();
		
		byte ret = (byte) (_b0 ^ _b1);
		return ret;
	}

	
	//  主要改进地
	private static byte[] RCXBase(byte[] input, String mKkey) {
		int x = 0;
		int y = 0;
		// key[]是S盒
		byte key[] = initKey(mKkey);
		int xorIndex;
		int a = 0;
		int c = 0;
		
		byte[] result = new byte[input.length];

		for (int i = 0; i < input.length; i++) {
			
			// 算法主要改进点
			//  & 0xff 只取低八位   0-255
			x = (x + 1) &  0xff ;
			y = ((key[x] & 0xff) + y)  & 0xff;
			
			a = input[i];
			c = a ^ key[(key[x] + key[y]) & 0xff ];
			result[i] = (byte) c ;
			//  交换key[x] key[y]
			byte tmp = key[x];
			key[x] = key[y];
			key[y] = tmp;
			y = (y + a + c);
			// 得到随机数 xorIndex 对 result做更改
		}
		
		return result;
	}
	
	static String getRadomTestDataString  () {
		String testDataString = "";
		for(int count_store_length = 0;count_store_length<37;count_store_length++) {
			 int random_num = new Random().nextInt(27);
			 testDataString += (char)store[random_num];	 
		};
		return testDataString;
		};
		
		public static void test_break() {
			// 测试破解密钥
			Long count_timeLong = 0L;
			String try_Str_keyString = "";
			String try_Str_data = encry_RCX_string("47e1316770c4429798c233bfaeffb9baF3", aim_keyString);
			long startTime = System.currentTimeMillis();
			
		// 假设7位密钥 暴力破解  "5b2ae3b"
			for(int s0 = 0;s0 < aim_key.length;s0++) {
			for(int s1 = 0;s1 < aim_key.length;s1++) {
				for(int s2 = 0;s2 < aim_key.length;s2++) {
					for(int s3 = 0;s3 < aim_key.length;s3++) {
						for(int s4 = 0;s4 < aim_key.length;s4++) {
							for(int s5 = 0;s5 < aim_key.length;s5++) {
								for(int s6 = 0;s6 < aim_key.length;s6++) {
									
									try_Str_keyString += (char)(aim_key[s0]);
									try_Str_keyString += (char)(aim_key[s1]);
									try_Str_keyString += (char)(aim_key[s2]);
									try_Str_keyString += (char)(aim_key[s3]);
									try_Str_keyString += (char)(aim_key[s4]);
									try_Str_keyString += (char)(aim_key[s5]);
									try_Str_keyString += (char)(aim_key[s6]);
									
									String ans = decry_RCX(try_Str_data,try_Str_keyString);
									
									
									if(try_Str_keyString.equals(aim_keyString)) {
										System.out.println("破解，得到结果为"+ans);
										long endTime = System.currentTimeMillis();
										float excTime = (float)(endTime-startTime)/1000;
										System.out.println("执行时间为:"+excTime+"s" );
										return;
									};	
										System.out.println("失败");
										System.out.println("使用测试数据:"+try_Str_keyString);
										try_Str_keyString = "";
										try {
											Thread.sleep((long) 0.3);
										} catch (InterruptedException e) {
											
											e.printStackTrace();
										}
										

								};
							};
						};
					};
				};
			};
			
		};
		}
			
	public static void main(String[] args) {
//		String inputStr = "ABCDDDDDDDDDDDDDDDDDDDDDDGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGAAAAAAAAAAAAAAAAAAA";
//		String str = encry_RC4_string(inputStr, "5");
//		System.out.println(str);
//		System.out.println(decry_RC4(str, "5"));		
		
		// 随机生成需要加密数据
              		  
		// 开始时间
//		long startTime = System.currentTimeMillis();
//		
//		for(Long testcount = (long) 0;testcount<1000;testcount++) {
//			String testData = getRadomTestDataString();
//			decry_RCX(encry_RCX_string( testData, "5B2AE3BC-5232-4102-8E60-3DB96993E229-YEMD"), "5B2AE3BC-5232-4102-8E60-3DB96993E229-YEMD");
//			
//		};
//		
////		
//		// 结束时间
//		long endTime = System.currentTimeMillis();
//		float excTime = (float)(endTime-startTime)/1 000;
//		System.out.println("执行时间为:"+excTime+"s" );
//		
		// 测试破解需要时间
		
		test_break();
   

		
	}
}


