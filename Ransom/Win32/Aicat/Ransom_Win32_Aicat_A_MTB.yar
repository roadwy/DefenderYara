
rule Ransom_Win32_Aicat_A_MTB{
	meta:
		description = "Ransom:Win32/Aicat.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 "
		
	strings :
		$a_00_0 = {8a 06 88 07 8a 46 01 88 47 01 8a 46 02 88 47 02 8b 45 08 } //10
		$a_81_1 = {78 78 78 78 2e 6f 6e 69 6f 6e } //3 xxxx.onion
		$a_81_2 = {5c 52 78 32 6f 37 64 2e 74 78 74 } //3 \Rx2o7d.txt
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3) >=16
 
}