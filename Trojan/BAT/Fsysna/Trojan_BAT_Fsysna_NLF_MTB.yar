
rule Trojan_BAT_Fsysna_NLF_MTB{
	meta:
		description = "Trojan:BAT/Fsysna.NLF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {73 31 00 00 0a 80 ?? ?? ?? 04 20 ?? ?? ?? 00 38 ?? ?? ?? ff 20 ?? ?? ?? 06 20 ?? ?? ?? 86 58 20 ?? ?? ?? fb 61 7e ?? ?? ?? 04 7b ?? ?? ?? 04 61 7e ?? ?? ?? 04 28 ?? ?? ?? 06 } //5
		$a_01_1 = {64 00 6c 00 65 00 78 00 65 00 63 00 } //1 dlexec
		$a_01_2 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}