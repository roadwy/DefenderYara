
rule Trojan_Win32_Redline_ASCC_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {79 79 72 67 61 70 64 7a 63 64 65 78 78 77 6c 66 74 75 6c 6b 71 71 79 6a 68 72 67 61 } //01 00  yyrgapdzcdexxwlftulkqqyjhrga
		$a_01_1 = {6b 66 62 74 6a 67 79 6a 70 6e 69 77 68 73 61 78 75 78 74 69 62 69 64 73 71 7a 71 67 67 61 6a 73 6c 6f 6d 62 6f 6b 61 66 71 6d 6f 74 68 6e 75 66 78 76 62 71 74 61 72 75 64 6b 74 7a 61 6e 7a 79 6c 6f 7a 77 6f 6c } //01 00  kfbtjgyjpniwhsaxuxtibidsqzqggajslombokafqmothnufxvbqtarudktzanzylozwol
		$a_01_2 = {63 61 77 71 71 77 63 6b 7a 69 74 79 6d 66 66 7a 6a 65 7a 78 74 69 } //01 00  cawqqwckzitymffzjezxti
		$a_01_3 = {76 73 71 64 78 75 7a 65 7a 66 6d 78 69 73 67 65 67 6a 66 65 61 68 6f 71 67 6b 62 6a 68 75 66 } //01 00  vsqdxuzezfmxisgegjfeahoqgkbjhuf
		$a_01_4 = {66 79 74 6d 75 6a 6c 6a 6f 76 61 6c 79 69 69 6f 66 75 71 66 70 6c 67 78 6f 72 74 71 67 62 6d 77 70 69 79 74 68 6d 62 } //00 00  fytmujljovalyiiofuqfplgxortqgbmwpiythmb
	condition:
		any of ($a_*)
 
}