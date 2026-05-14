
rule Trojan_BAT_Runner_GPSG_MTB{
	meta:
		description = "Trojan:BAT/Runner.GPSG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 53 41 69 4e 32 45 77 4f 54 49 35 4e 6a 45 30 4f 55 46 6b 4e 7a 55 33 4e 44 56 6b 4f 44 41 31 51 30 5a 6a 4e 47 4e 6c 4d 6a 45 31 4e 54 63 7a 59 6a 51 30 } //5 PSAiN2EwOTI5NjE0OUFkNzU3NDVkODA1Q0ZjNGNlMjE1NTczYjQ0
	condition:
		((#a_01_0  & 1)*5) >=5
 
}