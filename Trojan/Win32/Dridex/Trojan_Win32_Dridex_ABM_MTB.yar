
rule Trojan_Win32_Dridex_ABM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.ABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {67 66 6b 75 61 69 74 68 70 74 } //gfkuaithpt  03 00 
		$a_80_1 = {72 73 2d 6c 36 5a } //rs-l6Z  03 00 
		$a_80_2 = {54 72 79 41 63 71 75 69 72 65 53 52 57 4c 6f 63 6b 45 78 63 6c 75 73 69 76 65 } //TryAcquireSRWLockExclusive  03 00 
		$a_80_3 = {52 65 6c 65 61 73 65 53 52 57 4c 6f 63 6b 45 78 63 6c 75 73 69 76 65 } //ReleaseSRWLockExclusive  03 00 
		$a_80_4 = {73 65 72 76 69 63 65 2e 64 6c 6c } //service.dll  03 00 
		$a_80_5 = {53 65 72 76 69 63 65 4d 61 69 6e } //ServiceMain  03 00 
		$a_80_6 = {46 70 3a 70 79 46 78 32 } //Fp:pyFx2  00 00 
	condition:
		any of ($a_*)
 
}