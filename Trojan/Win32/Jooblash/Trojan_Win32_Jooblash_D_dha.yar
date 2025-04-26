
rule Trojan_Win32_Jooblash_D_dha{
	meta:
		description = "Trojan:Win32/Jooblash.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_80_0 = {62 34 62 36 31 35 63 32 38 63 63 64 30 35 39 63 66 38 65 64 31 61 62 66 31 63 37 31 66 65 30 33 63 30 33 35 34 35 32 32 39 39 30 61 66 36 33 61 64 66 33 63 39 31 31 65 32 32 38 37 61 34 62 39 30 36 64 34 37 64 } //b4b615c28ccd059cf8ed1abf1c71fe03c0354522990af63adf3c911e2287a4b906d47d  1
	condition:
		((#a_80_0  & 1)*1) >=1
 
}