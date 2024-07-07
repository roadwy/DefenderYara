
rule Trojan_Win32_Vidar_BA_MTB{
	meta:
		description = "Trojan:Win32/Vidar.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c8 8b 45 fc 33 d2 f7 f1 8b 45 0c 8b 4d 08 8a 04 02 32 04 31 ff 45 fc 88 06 39 5d fc 72 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}