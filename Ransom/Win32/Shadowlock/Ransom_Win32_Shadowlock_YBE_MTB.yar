
rule Ransom_Win32_Shadowlock_YBE_MTB{
	meta:
		description = "Ransom:Win32/Shadowlock.YBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {59 4f 55 52 20 45 4d 50 49 52 45 20 49 53 20 41 53 48 45 53 } //1 YOUR EMPIRE IS ASHES
		$a_01_1 = {45 4e 54 45 52 20 50 41 53 53 57 4f 52 44 20 54 4f 20 55 4e 4c 4f 43 4b } //1 ENTER PASSWORD TO UNLOCK
		$a_01_2 = {53 48 41 44 4f 57 4c 4f 43 4b } //1 SHADOWLOCK
		$a_01_3 = {50 41 59 20 4f 52 20 44 49 45 } //1 PAY OR DIE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}