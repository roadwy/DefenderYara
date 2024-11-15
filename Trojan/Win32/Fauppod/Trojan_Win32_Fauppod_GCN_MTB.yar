
rule Trojan_Win32_Fauppod_GCN_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.GCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 28 8d 05 ?? ?? ?? ?? 89 18 83 e8 ?? 01 d0 31 d0 89 f8 50 8f 05 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}