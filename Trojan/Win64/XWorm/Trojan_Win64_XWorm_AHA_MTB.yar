
rule Trojan_Win64_XWorm_AHA_MTB{
	meta:
		description = "Trojan:Win64/XWorm.AHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_01_0 = {5b 2a 5d 20 43 6f 6e 73 6f 6c 65 20 6d 6f 64 65 20 61 63 74 69 76 65 } //10 [*] Console mode active
		$a_01_1 = {5b 2d 5d 20 55 41 43 20 72 65 66 75 73 65 64 2e 20 52 65 74 72 79 69 6e 67 20 69 6e 20 32 20 73 65 63 2e 2e 2e } //30 [-] UAC refused. Retrying in 2 sec...
		$a_01_2 = {5b 2a 5d 20 52 75 6e 6e 69 6e 67 20 61 73 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 } //20 [*] Running as Administrator
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*30+(#a_01_2  & 1)*20) >=60
 
}