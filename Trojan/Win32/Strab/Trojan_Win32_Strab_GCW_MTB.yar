
rule Trojan_Win32_Strab_GCW_MTB{
	meta:
		description = "Trojan:Win32/Strab.GCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 d0 30 c8 20 d0 88 d5 80 f5 ?? 88 e1 20 e9 80 f4 ?? 20 e2 08 d1 88 c2 20 ca 30 c8 08 c2 b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? f6 c2 ?? 0f 45 c1 89 45 ?? e9 } //10
		$a_01_1 = {5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 65 73 6b 74 6f 70 5c 65 72 72 6f 72 2e 74 78 74 } //1 \Users\Public\Desktop\error.txt
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}