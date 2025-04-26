
rule Trojan_Win32_Lisiu_A{
	meta:
		description = "Trojan:Win32/Lisiu.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {7e 09 80 34 31 02 41 3b c8 7c f7 } //2
		$a_01_1 = {0f b6 ca d2 e0 0a d8 ff 45 fc 83 7d fc 08 88 1c 37 75 04 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=2
 
}