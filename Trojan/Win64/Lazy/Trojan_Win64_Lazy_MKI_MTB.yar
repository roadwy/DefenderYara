
rule Trojan_Win64_Lazy_MKI_MTB{
	meta:
		description = "Trojan:Win64/Lazy.MKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 04 00 00 "
		
	strings :
		$a_81_0 = {5b 2a 5d 20 42 59 50 41 53 53 20 53 54 41 52 54 45 44 2e } //20 [*] BYPASS STARTED.
		$a_81_1 = {5b 2b 5d 20 44 4e 53 20 46 52 45 45 5a 45 20 41 50 50 4c 49 45 44 21 } //15 [+] DNS FREEZE APPLIED!
		$a_81_2 = {5b 2d 5d 20 56 47 43 20 4e 4f 54 20 46 4f 55 4e 44 21 } //10 [-] VGC NOT FOUND!
		$a_81_3 = {5b 2b 5d 20 43 50 55 20 53 50 49 4b 45 20 44 45 54 45 43 54 45 44 21 20 41 50 50 4c 59 49 4e 47 20 44 4e 53 20 46 52 45 45 5a 45 } //5 [+] CPU SPIKE DETECTED! APPLYING DNS FREEZE
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*15+(#a_81_2  & 1)*10+(#a_81_3  & 1)*5) >=50
 
}