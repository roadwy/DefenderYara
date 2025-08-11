
rule Trojan_Win32_Stealer_DAG_MTB{
	meta:
		description = "Trojan:Win32/Stealer.DAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 8c 01 d0 31 cb 89 da 88 10 83 85 ?? ?? ?? ?? ?? 8b 45 88 3b 85 ?? ?? ?? ?? 0f 8f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}