
rule Trojan_Win64_Tedy_GPP_MTB{
	meta:
		description = "Trojan:Win64/Tedy.GPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 43 56 45 2d 32 30 32 34 2d 32 30 36 35 36 5c 45 78 70 6c 5c 78 36 34 5c 52 65 6c 65 61 73 65 } //1 source\repos\CVE-2024-20656\Expl\x64\Release
	condition:
		((#a_01_0  & 1)*1) >=1
 
}