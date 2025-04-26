
rule Trojan_Win32_Fsysna_GMX_MTB{
	meta:
		description = "Trojan:Win32/Fsysna.GMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 d2 02 d2 c0 eb 04 0a d3 88 16 0f b6 50 01 0f b6 18 0f b6 94 15 ?? ?? ?? ?? 0f b6 9c 1d ?? ?? ?? ?? c0 ea 02 c0 e3 04 0a d3 88 56 01 0f b6 50 01 0f b6 94 15 ?? ?? ?? ?? 0f b6 58 02 c0 e2 06 0a 94 1d ?? ?? ?? ?? 83 c6 03 88 56 ff 83 c0 04 4f } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}