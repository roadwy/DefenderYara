
rule Trojan_Win64_RaStealer_PAE_MTB{
	meta:
		description = "Trojan:Win64/RaStealer.PAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 2b c2 48 83 f8 02 72 ?? 80 f9 0d 75 ?? ?? ?? ?? ?? ?? 0a 74 ?? 80 f9 0a 74 [0-04] 0f 85 ?? ?? ?? ?? 80 f9 3d 75 [0-0a] 0f 87 ?? ?? ?? ?? 80 f9 7c } //1
		$a_03_1 = {33 c0 80 f9 40 0f 94 c0 83 e1 3f 49 [0-03] 44 2b ?? 41 8b ?? 44 8b ?? c1 e0 06 44 0b ?? 49 83 fb 04 75 ?? 45 33 db 45 85 ?? 74 ?? 41 8b ?? c1 e8 10 88 02 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}