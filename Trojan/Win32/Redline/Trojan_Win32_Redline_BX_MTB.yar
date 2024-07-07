
rule Trojan_Win32_Redline_BX_MTB{
	meta:
		description = "Trojan:Win32/Redline.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 ca 88 4d fb 0f be 45 fb 0f be 4d fb 03 c1 8b 55 0c 03 55 fc 88 02 0f be 45 fb 8b 4d 0c 03 4d fc 0f be 11 2b d0 8b 45 0c 03 45 fc 88 10 eb } //2
		$a_01_1 = {f7 f9 8b 55 0c 03 55 fc 0f b6 0a 33 c8 8b 55 0c 03 55 fc 88 0a eb } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}