
rule Trojan_Win32_Razy_AD_MTB{
	meta:
		description = "Trojan:Win32/Razy.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {09 c0 bf d8 85 40 00 e8 ?? ?? ?? ?? 31 3b 81 c3 ?? ?? ?? ?? 81 e8 ?? ?? ?? ?? 39 cb 75 e4 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}