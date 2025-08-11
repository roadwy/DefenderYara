
rule Trojan_Win64_PawFall_A{
	meta:
		description = "Trojan:Win64/PawFall.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 00 53 00 45 00 56 00 45 00 4e 00 37 00 37 00 37 00 37 00 00 00 } //1
		$a_01_1 = {00 56 69 72 74 75 61 6c 41 6c 6c 6f 63 00 } //1 嘀物畴污汁潬c
		$a_03_2 = {c1 ea 04 6b ?? 42 2b ?? 48 ?? ?? 42 0f b6 ?? ?? (41|30) } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=2
 
}