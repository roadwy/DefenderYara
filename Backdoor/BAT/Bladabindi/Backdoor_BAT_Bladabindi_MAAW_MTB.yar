
rule Backdoor_BAT_Bladabindi_MAAW_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.MAAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {24 37 31 46 45 44 30 43 45 2d 32 31 39 32 2d 34 35 36 38 2d 41 38 43 46 2d 37 44 45 33 36 31 30 32 31 45 43 46 } //1 $71FED0CE-2192-4568-A8CF-7DE361021ECF
		$a_01_1 = {24 64 65 65 35 37 36 61 63 2d 31 36 62 33 2d 34 30 35 37 2d 61 32 62 62 2d 65 66 63 37 66 63 32 64 61 65 30 63 } //1 $dee576ac-16b3-4057-a2bb-efc7fc2dae0c
		$a_01_2 = {24 66 64 66 31 35 63 35 65 2d 33 36 64 64 2d 34 34 35 35 2d 38 36 30 30 2d 36 61 37 65 39 33 65 30 38 63 33 34 } //1 $fdf15c5e-36dd-4455-8600-6a7e93e08c34
		$a_01_3 = {24 34 31 31 35 61 66 63 34 2d 61 31 37 34 2d 34 62 64 63 2d 61 63 61 66 2d 63 63 31 39 63 61 34 65 33 65 35 30 } //1 $4115afc4-a174-4bdc-acaf-cc19ca4e3e50
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}