
rule Trojan_Win32_TangentCobra_B_dha{
	meta:
		description = "Trojan:Win32/TangentCobra.B!dha,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 42 31 34 34 30 44 39 30 46 43 39 42 43 42 34 36 41 39 41 43 39 36 34 33 38 46 45 45 41 38 42 } //1 1B1440D90FC9BCB46A9AC96438FEEA8B
	condition:
		((#a_01_0  & 1)*1) >=1
 
}