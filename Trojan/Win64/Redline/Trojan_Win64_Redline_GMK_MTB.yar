
rule Trojan_Win64_Redline_GMK_MTB{
	meta:
		description = "Trojan:Win64/Redline.GMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {34 40 00 ff 34 40 90 01 02 bc 97 44 7a f1 bf 58 3a b0 f6 20 6b b0 fe 80 56 b0 5b 94 90 00 } //01 00 
		$a_01_1 = {58 62 6a 73 34 32 68 73 34 7a } //00 00 
	condition:
		any of ($a_*)
 
}