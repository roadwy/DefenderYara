
rule Trojan_BAT_LummaStealer_AMAA_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 07 38 ?? 00 00 00 11 07 13 08 38 } //4
		$a_80_1 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources  1
	condition:
		((#a_03_0  & 1)*4+(#a_80_1  & 1)*1) >=5
 
}