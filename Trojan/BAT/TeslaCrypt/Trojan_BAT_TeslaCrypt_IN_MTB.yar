
rule Trojan_BAT_TeslaCrypt_IN_MTB{
	meta:
		description = "Trojan:BAT/TeslaCrypt.IN!MTB,SIGNATURE_TYPE_PEHSTR,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //1 CompressionMode
		$a_01_1 = {42 69 74 43 6f 6e 76 65 72 74 65 72 } //1 BitConverter
		$a_01_2 = {54 6f 49 6e 74 33 32 } //1 ToInt32
		$a_01_3 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_4 = {67 65 74 5f 52 } //1 get_R
		$a_01_5 = {67 65 74 5f 47 } //1 get_G
		$a_01_6 = {67 65 74 5f 42 } //1 get_B
		$a_01_7 = {52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //1 ResourceManager
		$a_01_8 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_9 = {53 6c 65 65 70 } //1 Sleep
		$a_01_10 = {53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 } //1 System.Threading
		$a_01_11 = {4d 65 74 68 6f 64 42 61 73 65 } //1 MethodBase
		$a_01_12 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_13 = {6e 00 65 00 76 00 65 00 72 00 20 00 6c 00 65 00 74 00 20 00 79 00 6f 00 75 00 72 00 73 00 65 00 6c 00 66 00 20 00 62 00 65 00 20 00 64 00 65 00 66 00 65 00 61 00 74 00 65 00 64 00 } //1 never let yourself be defeated
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=14
 
}