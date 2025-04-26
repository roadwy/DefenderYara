
rule Trojan_Win32_Lazy_GMB_MTB{
	meta:
		description = "Trojan:Win32/Lazy.GMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {52 83 c4 04 83 c6 01 8a 46 ff 68 ?? ?? ?? ?? 83 c4 04 c7 44 24 ?? db 83 dd a3 32 02 68 ?? ?? ?? ?? 83 c4 04 83 c7 01 88 47 ff 89 c0 68 ?? ?? ?? ?? 83 c4 04 83 c2 02 4a 83 ec 04 c7 04 24 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}