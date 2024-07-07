
rule Trojan_Win32_Riern_A{
	meta:
		description = "Trojan:Win32/Riern.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 a1 30 00 00 00 8b 40 0c 8b 70 1c ad 8b 40 08 5e 89 45 fc 8b 75 fc 85 f6 74 2f 68 48 1e 35 d2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}