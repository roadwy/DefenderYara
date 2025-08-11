
rule Trojan_Win32_Stealer_DAD_MTB{
	meta:
		description = "Trojan:Win32/Stealer.DAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 1c 16 30 cb 88 1c 16 42 39 94 24 ?? ?? ?? ?? 89 fb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}