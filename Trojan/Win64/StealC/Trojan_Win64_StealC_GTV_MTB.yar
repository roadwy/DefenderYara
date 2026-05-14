
rule Trojan_Win64_StealC_GTV_MTB{
	meta:
		description = "Trojan:Win64/StealC.GTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {ba 02 00 00 00 48 8d 8d 70 03 00 00 ff 15 ?? ?? ?? ?? 45 33 c9 c7 44 24 ?? 01 00 00 00 4c 8d 85 70 03 00 00 48 89 7c 24 20 48 8d 15 ?? ?? ?? ?? 33 c9 ff 15 } //10
		$a_01_1 = {5c 43 6c 69 70 70 65 72 44 72 6f 70 70 65 72 2e 70 64 62 } //1 \ClipperDropper.pdb
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}