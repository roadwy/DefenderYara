
rule Trojan_BAT_Heracles_GPAV_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GPAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_81_0 = {63 63 63 61 61 61 69 69 69 2f 54 65 73 74 2d 31 32 2f 72 65 66 73 2f 68 65 61 64 73 2f 6d 61 69 6e 2f 44 65 73 69 67 6e 74 69 6d 65 72 65 73 6f 6c 76 65 72 2e 65 78 65 2e 63 6f 6e 66 69 67 } //8 cccaaaiii/Test-12/refs/heads/main/Designtimeresolver.exe.config
	condition:
		((#a_81_0  & 1)*8) >=8
 
}