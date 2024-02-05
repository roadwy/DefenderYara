
rule Trojan_Win64_TrikBot_PAB_MTB{
	meta:
		description = "Trojan:Win64/TrikBot.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e0 02 0f be 4c 24 90 01 01 83 e1 30 c1 f9 04 01 c8 88 44 24 90 01 01 0f be 44 24 90 01 01 83 e0 0f c1 e0 04 0f be 4c 24 90 01 01 83 e1 3c c1 f9 02 01 c8 88 44 24 90 01 01 0f be 44 24 90 01 01 83 e0 03 c1 e0 06 0f be 4c 24 90 01 01 01 c8 88 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}