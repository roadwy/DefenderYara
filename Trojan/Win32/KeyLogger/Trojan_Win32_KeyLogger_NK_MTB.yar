
rule Trojan_Win32_KeyLogger_NK_MTB{
	meta:
		description = "Trojan:Win32/KeyLogger.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c0 55 68 aa c1 49 00 64 ff 30 64 89 20 6a 00 8b 4d fc b2 01 a1 34 7c 41 00 e8 ?? ?? ?? ?? 8b d8 8b c3 } //3
		$a_01_1 = {7a 69 70 70 61 73 73 77 6f 72 64 3d 64 61 6d 61 67 65 6c 61 62 } //1 zippassword=damagelab
		$a_01_2 = {66 74 70 3d 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 } //1 ftp=xxxxxxxxxxxxxxx
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}