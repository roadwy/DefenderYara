
rule Virus_Win32_Floxif_RDA_MTB{
	meta:
		description = "Virus:Win32/Floxif.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 85 78 ff ff ff 33 d2 f7 75 94 8b 85 64 fe ff ff 0f be 14 10 33 ca 8b 45 90 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}