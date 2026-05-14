
rule Trojan_Win64_Shellcode_PGSH_MTB{
	meta:
		description = "Trojan:Win64/Shellcode.PGSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d9 c1 f9 ?? 29 ca 44 8d 0c d2 46 8d 0c 4a 89 da 44 29 ca 48 63 d2 0f b6 14 16 41 30 10 48 69 c0 ?? ?? ?? ?? 48 c1 f8 ?? 29 c8 69 c0 ?? ?? ?? ?? 39 d8 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}