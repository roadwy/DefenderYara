
rule Trojan_Win32_StealC_SPCB_MTB{
	meta:
		description = "Trojan:Win32/StealC.SPCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 74 24 0c c7 44 24 14 ?? ?? ?? ?? c7 44 24 0c ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 44 24 0c 83 c0 46 89 44 24 14 90 90 83 6c 24 14 46 8a 44 24 14 30 04 1f 47 3b fd 7c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}