
rule Trojan_Win32_Copak_GME_MTB{
	meta:
		description = "Trojan:Win32/Copak.GME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 5f 21 d9 e8 ?? ?? ?? ?? 43 09 d9 31 38 49 40 81 e9 ?? ?? ?? ?? 29 cb 49 39 f0 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}