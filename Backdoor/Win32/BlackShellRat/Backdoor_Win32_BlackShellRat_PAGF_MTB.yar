
rule Backdoor_Win32_BlackShellRat_PAGF_MTB{
	meta:
		description = "Backdoor:Win32/BlackShellRat.PAGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {5b 42 7e 6c 7e 61 7e 63 7e 6b 7e 53 7e 68 7e 65 7e 6c 7e 6c 5d } //3 [B~l~a~c~k~S~h~e~l~l]
		$a_01_1 = {5c 71 75 69 63 6b 73 74 61 72 74 2e 65 78 65 } //2 \quickstart.exe
		$a_01_2 = {5c 63 6d 64 2e 65 78 65 } //1 \cmd.exe
		$a_01_3 = {50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //1 Program Files\Internet Explorer\iexplore.exe
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}