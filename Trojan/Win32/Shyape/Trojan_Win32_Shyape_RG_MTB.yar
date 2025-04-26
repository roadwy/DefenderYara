
rule Trojan_Win32_Shyape_RG_MTB{
	meta:
		description = "Trojan:Win32/Shyape.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 55 18 32 d1 eb 0f 8b 55 10 8b 75 08 03 f2 8a 16 32 d1 02 55 18 ff 45 10 88 16 8b 4d 10 3b 4d 0c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}