
rule Trojan_Win64_Dtrack_B_dha{
	meta:
		description = "Trojan:Win64/Dtrack.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,fffffff4 01 fffffff4 01 05 00 00 "
		
	strings :
		$a_01_0 = {2f 63 20 69 70 63 6f 6e 66 69 67 20 2f 61 6c 6c 20 3e 20 22 25 73 22 20 26 20 74 61 73 6b 6c 69 73 74 20 3e 20 22 25 73 22 20 26 20 6e 65 74 73 74 61 74 20 2d 6e 61 6f 70 20 74 63 70 20 3e 20 22 25 73 22 } //100 /c ipconfig /all > "%s" & tasklist > "%s" & netstat -naop tcp > "%s"
		$a_01_1 = {2f 63 20 70 69 6e 67 20 2d 6e 20 33 20 31 32 37 2e 30 2e 30 2e 31 20 3e 4e 55 4c 20 26 20 65 63 68 6f 20 45 45 45 45 20 3e 20 22 25 73 22 } //100 /c ping -n 3 127.0.0.1 >NUL & echo EEEE > "%s"
		$a_01_2 = {25 73 5c 6e 65 74 73 74 61 74 2e 72 65 73 } //100 %s\netstat.res
		$a_01_3 = {25 73 5c 74 61 73 6b 2e 6c 69 73 74 } //100 %s\task.list
		$a_01_4 = {25 73 5c 72 65 73 2e 69 70 } //100 %s\res.ip
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100+(#a_01_4  & 1)*100) >=500
 
}