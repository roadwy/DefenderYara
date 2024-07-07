
rule Trojan_Win32_Zenpak_ASAH_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 4d fe 0f b6 55 ff 31 d1 88 cc } //2
		$a_01_1 = {55 89 e5 50 8a 45 0c 8a 4d 08 88 45 ff 88 4d fd 8a 45 fd 88 45 fe } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}