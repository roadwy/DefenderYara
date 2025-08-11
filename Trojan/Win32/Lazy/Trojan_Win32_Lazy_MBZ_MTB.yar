
rule Trojan_Win32_Lazy_MBZ_MTB{
	meta:
		description = "Trojan:Win32/Lazy.MBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 20 49 44 3a 20 22 4e 32 49 4c 4e 62 55 69 6d 49 58 43 45 30 49 4d 56 5f 78 64 2f 43 69 6e 39 34 5a 43 53 50 51 50 56 61 67 51 53 43 70 61 30 2f 63 54 35 42 6b 48 57 4b 7a 68 79 42 30 51 46 65 6d } //1 d ID: "N2ILNbUimIXCE0IMV_xd/Cin94ZCSPQPVagQSCpa0/cT5BkHWKzhyB0QFem
	condition:
		((#a_01_0  & 1)*1) >=1
 
}