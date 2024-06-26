
rule PWS_Win32_Fireming_A{
	meta:
		description = "PWS:Win32/Fireming.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 02 00 "
		
	strings :
		$a_03_0 = {3d c8 00 00 00 0f 85 90 01 02 00 00 c7 44 24 18 00 00 00 00 c7 44 24 14 80 00 00 00 c7 44 24 10 02 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 02 00 00 00 c7 44 24 04 00 00 00 40 90 02 06 89 04 24 e8 90 00 } //01 00 
		$a_01_1 = {25 73 3f 75 73 65 72 3d 25 73 26 6d 6f 64 3d 6c 6f 67 } //01 00  %s?user=%s&mod=log
		$a_01_2 = {25 73 3f 6d 6f 64 3d 6c 6f 67 26 75 73 65 72 3d 25 73 } //01 00  %s?mod=log&user=%s
		$a_01_3 = {68 74 74 70 3a 2f 2f 25 73 3a 25 69 25 73 3f 6d 6f 64 3d 63 6d 64 } //01 00  http://%s:%i%s?mod=cmd
		$a_01_4 = {3c 62 3e 50 6f 73 74 44 61 74 61 3a 20 3c 2f 62 3e 25 73 3c 62 72 3e } //01 00  <b>PostData: </b>%s<br>
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 59 48 65 6c 70 65 72 } //01 00  Software\YHelper
		$a_01_6 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 47 65 63 6b 6f 2f 32 30 30 35 30 32 31 32 20 46 69 72 65 66 6f 78 2f 31 2e 35 2e 30 2e 32 } //00 00  Mozilla/5.0 Gecko/20050212 Firefox/1.5.0.2
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_Fireming_A_2{
	meta:
		description = "PWS:Win32/Fireming.A,SIGNATURE_TYPE_PEHSTR,0b 00 0a 00 0f 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 75 73 65 72 66 69 6c 65 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 25 73 22 } //01 00  Content-Disposition: form-data; name="userfile"; filename="%s"
		$a_01_1 = {25 73 5c 68 6c 73 74 2e 74 6d 70 } //01 00  %s\hlst.tmp
		$a_01_2 = {6d 75 6c 74 69 73 63 73 68 73 } //01 00  multiscshs
		$a_01_3 = {25 73 5c 64 6c 6c 63 61 63 68 65 5c 25 73 } //01 00  %s\dllcache\%s
		$a_01_4 = {25 73 75 73 65 72 69 6e 69 74 2e 65 78 65 2c } //01 00  %suserinit.exe,
		$a_01_5 = {25 73 61 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00  %sautorun.inf
		$a_01_6 = {25 73 5f 5f 50 53 2e 74 78 74 } //01 00  %s__PS.txt
		$a_01_7 = {57 69 6e 64 6f 77 73 20 53 65 72 76 65 72 20 32 30 30 33 } //01 00  Windows Server 2003
		$a_01_8 = {2e 68 74 6d 2a 2e 70 68 70 2a 2e 64 6f 2a 2e 61 73 70 2a 2e 6a 73 70 2a 3f } //01 00  .htm*.php*.do*.asp*.jsp*?
		$a_01_9 = {25 73 25 73 25 73 26 63 6e 74 3d 25 73 26 68 70 3d 25 64 26 73 70 3d 25 64 } //01 00  %s%s%s&cnt=%s&hp=%d&sp=%d
		$a_01_10 = {31 37 32 2e 31 36 2e } //01 00  172.16.
		$a_01_11 = {53 4f 43 4b 5f 53 45 51 50 41 43 4b 45 54 } //01 00  SOCK_SEQPACKET
		$a_01_12 = {00 70 73 74 2e 64 61 74 00 } //01 00 
		$a_01_13 = {65 62 61 79 2e 63 6f 2e 75 6b } //01 00  ebay.co.uk
		$a_01_14 = {61 6d 61 7a 6f 6e 2e 63 6f 2e 75 6b } //00 00  amazon.co.uk
	condition:
		any of ($a_*)
 
}