
rule Trojan_Win32_Farfli_Z_MTB{
	meta:
		description = "Trojan:Win32/Farfli.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 86 0c 01 00 00 8b ce 50 e8 ?? ?? 00 00 8b 1d ?? ?? ?? ?? 8d be 0c 02 00 00 57 ff d3 6a 5c 57 ff 15 ?? ?? ?? ?? 59 89 45 f0 85 c0 59 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}