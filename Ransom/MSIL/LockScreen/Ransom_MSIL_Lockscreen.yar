
rule Ransom_MSIL_Lockscreen{
	meta:
		description = "Ransom:MSIL/Lockscreen,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {59 00 6f 00 75 00 72 00 20 00 75 00 6e 00 6c 00 6f 00 63 00 6b 00 20 00 63 00 6f 00 64 00 65 00 20 00 67 00 6f 00 65 00 73 00 20 00 68 00 65 00 72 00 65 00 } //1 Your unlock code goes here
		$a_01_1 = {55 00 6e 00 6c 00 6f 00 63 00 6b 00 } //1 Unlock
		$a_01_2 = {59 00 6f 00 75 00 72 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 77 00 61 00 73 00 20 00 75 00 6e 00 6c 00 6f 00 63 00 6b 00 65 00 64 00 20 00 77 00 69 00 74 00 68 00 } //1 Your computer was unlocked with
		$a_01_3 = {45 00 6c 00 6d 00 65 00 72 00 4c 00 6f 00 63 00 6b 00 } //1 ElmerLock
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}