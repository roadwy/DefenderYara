
rule Trojan_Win64_Rootkit_ARA_MTB{
	meta:
		description = "Trojan:Win64/Rootkit.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_80_0 = {3a 5c 55 73 65 72 73 5c 42 61 61 74 5c 44 65 73 6b 74 6f 70 5c 47 50 54 20 31 2e 36 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 52 57 53 61 66 65 2e 70 64 62 } //:\Users\Baat\Desktop\GPT 1.6\x64\Release\RWSafe.pdb  2
	condition:
		((#a_80_0  & 1)*2) >=2
 
}