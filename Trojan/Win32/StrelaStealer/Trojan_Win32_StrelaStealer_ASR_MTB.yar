
rule Trojan_Win32_StrelaStealer_ASR_MTB{
	meta:
		description = "Trojan:Win32/StrelaStealer.ASR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 e8 b8 ?? ?? ?? ?? 8a 0a 32 4d ef 02 4d ef 88 0a 42 89 55 e8 c3 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}