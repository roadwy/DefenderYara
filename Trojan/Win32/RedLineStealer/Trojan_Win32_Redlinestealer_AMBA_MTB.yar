
rule Trojan_Win32_Redlinestealer_AMBA_MTB{
	meta:
		description = "Trojan:Win32/Redlinestealer.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 10 30 04 31 83 bc 24 ?? ?? ?? ?? ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}