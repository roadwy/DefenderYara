
rule Trojan_Win64_Androm_GBS_MTB{
	meta:
		description = "Trojan:Win64/Androm.GBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 8d 0c 10 80 e1 07 c0 e1 03 49 8b d3 48 d3 ea 41 30 50 ff 41 0f b6 c8 41 2a c9 80 e1 07 c0 e1 03 49 8b d3 48 d3 ea 41 30 10 49 83 c0 02 4b 8d 04 02 48 3d 52 07 } //00 00 
	condition:
		any of ($a_*)
 
}