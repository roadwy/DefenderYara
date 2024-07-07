
rule Trojan_Win32_Zlob_DSK_MTB{
	meta:
		description = "Trojan:Win32/Zlob.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c3 03 d0 81 e2 ff 00 00 00 8a 8a 90 01 04 30 0c 37 83 6d fc 01 8b 75 fc 85 f6 7d 90 09 05 00 a3 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}