
rule Trojan_Win32_Blackmoon_ARAF_MTB{
	meta:
		description = "Trojan:Win32/Blackmoon.ARAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {62 6c 61 63 6b 6d 6f 6f 6e } //2 blackmoon
		$a_01_1 = {3a 2f 2f 64 6c 6c 2d 31 33 30 30 33 35 35 31 37 39 2e 63 6f 73 2e 61 70 2d 73 68 61 6e 67 68 61 69 2e 6d 79 71 63 6c 6f 75 64 2e 63 6f 6d 2f } //2 ://dll-1300355179.cos.ap-shanghai.myqcloud.com/
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}