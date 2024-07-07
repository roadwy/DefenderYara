
rule Trojan_Win32_Tedy_SPGQ_MTB{
	meta:
		description = "Trojan:Win32/Tedy.SPGQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {36 36 34 46 69 72 73 78 78 64 66 64 74 4e 61 6d 65 } //1 664FirsxxdfdtName
		$a_01_1 = {63 64 65 66 63 64 65 66 63 64 65 66 63 64 65 66 63 64 65 66 68 74 74 70 3a 2f 2f 62 64 2e 74 6c 79 73 6a 2e 63 6f 6d 3a 37 39 37 39 2f 32 30 2e 6a 70 67 } //1 cdefcdefcdefcdefcdefhttp://bd.tlysj.com:7979/20.jpg
		$a_01_2 = {61 62 63 64 61 62 63 64 61 62 63 64 61 62 63 64 61 62 63 64 68 74 74 70 3a 2f 2f 38 30 33 2e 61 73 78 35 31 2e 69 6e 66 6f 3a 38 30 38 30 2f 32 30 2e 6a 70 67 } //1 abcdabcdabcdabcdabcdhttp://803.asx51.info:8080/20.jpg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}