
rule Trojan_Win32_Tedy_ARAF_MTB{
	meta:
		description = "Trojan:Win32/Tedy.ARAF!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {6d 00 61 00 69 00 6c 00 2e 00 6d 00 61 00 72 00 2d 00 68 00 6f 00 6c 00 69 00 64 00 61 00 79 00 73 00 2e 00 6e 00 65 00 74 00 } //2 mail.mar-holidays.net
		$a_01_1 = {63 00 3a 00 5c 00 78 00 5c 00 78 00 78 00 78 00 2e 00 74 00 78 00 74 00 } //2 c:\x\xxx.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}