
rule Trojan_Win64_LummaStealer_IP_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.IP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 c1 8b 0c 24 48 8b 54 24 20 88 04 0a } //01 00 
		$a_01_1 = {47 50 55 56 69 65 77 2e 70 64 62 } //00 00  GPUView.pdb
	condition:
		any of ($a_*)
 
}