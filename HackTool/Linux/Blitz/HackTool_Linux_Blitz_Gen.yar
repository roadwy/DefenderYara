
rule HackTool_Linux_Blitz_Gen{
	meta:
		description = "HackTool:Linux/Blitz.Gen,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 10 00 00 "
		
	strings :
		$a_01_0 = {2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 3e 46 61 73 74 65 72 20 74 68 61 6e 20 6c 69 67 68 74 3c 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d } //1 ---------------------->Faster than light<-----------------------------
		$a_01_1 = {2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 3e 75 73 65 20 6f 6e 6c 79 20 66 6f 72 20 74 65 73 74 69 6e 67 3c 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d } //1 --------------------->use only for testing<----------------------
		$a_01_2 = {55 73 65 3a 20 73 63 61 6e 20 5b 4f 50 54 49 4f 4e 53 5d 20 5b 5b 55 53 45 52 20 50 41 53 53 5d 5d 20 46 49 4c 45 5d 20 5b 49 50 73 2f 49 50 73 20 50 6f 72 74 20 46 49 4c 45 5d } //1 Use: scan [OPTIONS] [[USER PASS]] FILE] [IPs/IPs Port FILE]
		$a_01_3 = {2d 74 20 5b 4e 55 4d 54 48 52 45 41 44 53 5d 3a 20 43 68 61 6e 67 65 20 74 68 65 20 6e 75 6d 62 65 72 20 6f 66 20 74 68 72 65 61 64 73 20 75 73 65 64 2e 20 44 65 66 61 75 6c 74 20 69 73 20 } //1 -t [NUMTHREADS]: Change the number of threads used. Default is 
		$a_01_4 = {2d 6d 20 5b 4d 4f 44 45 5d 3a 20 43 68 61 6e 67 65 20 74 68 65 20 77 61 79 20 74 68 65 20 73 63 61 6e 20 77 6f 72 6b 73 2e 20 44 65 66 61 75 6c 74 20 69 73 20 25 64 } //1 -m [MODE]: Change the way the scan works. Default is %d
		$a_01_5 = {2d 66 20 5b 46 49 4e 41 4c 20 53 43 41 4e 5d 3a 20 44 6f 65 73 20 61 20 66 69 6e 61 6c 20 73 63 61 6e 20 6f 6e 20 66 6f 75 6e 64 20 73 65 72 76 65 72 73 2e 20 44 65 66 61 75 6c 74 20 69 73 } //1 -f [FINAL SCAN]: Does a final scan on found servers. Default is
		$a_01_6 = {55 73 65 20 2d 66 20 31 20 66 6f 72 20 41 2e 42 20 63 6c 61 73 73 20 2f 31 36 2e 20 44 65 66 61 75 6c 74 20 69 73 20 32 20 66 6f 72 20 41 2e 42 2e 43 20 2f 32 34 } //1 Use -f 1 for A.B class /16. Default is 2 for A.B.C /24
		$a_01_7 = {2d 69 20 5b 49 50 20 53 43 41 4e 5d 3a 20 75 73 65 20 2d 69 20 30 20 74 6f 20 73 63 61 6e 20 69 70 20 63 6c 61 73 73 20 41 2e 42 2e 20 44 65 66 61 75 6c 74 20 69 73 20 25 64 } //1 -i [IP SCAN]: use -i 0 to scan ip class A.B. Default is %d
		$a_01_8 = {69 66 20 79 6f 75 20 75 73 65 20 2d 69 20 30 20 74 68 65 6e 20 75 73 65 20 2e 2f 73 63 61 6e 20 2d 70 20 32 32 20 2d 69 20 30 20 70 20 31 39 32 2e 31 36 38 20 61 73 20 61 67 72 75 6d 65 6e } //1 if you use -i 0 then use ./scan -p 22 -i 0 p 192.168 as agrumen
		$a_01_9 = {25 2d 50 20 30 20 6c 65 61 76 65 20 64 65 66 61 75 6c 74 20 70 61 73 73 77 6f 72 64 20 75 6e 63 68 61 6e 67 65 64 2e 20 43 68 61 6e 67 65 73 20 70 61 73 73 77 6f 72 64 20 62 79 20 64 65 66 61 75 6c 74 } //1 %-P 0 leave default password unchanged. Changes password by default
		$a_01_10 = {2d 73 20 5b 54 49 4d 45 4f 55 54 5d 3a 20 43 68 61 6e 67 65 20 74 68 65 20 74 69 6d 65 6f 75 74 2e 20 44 65 66 61 75 6c 74 20 69 73 20 25 6c 64 } //1 -s [TIMEOUT]: Change the timeout. Default is %ld
		$a_01_11 = {2d 70 20 5b 50 4f 52 54 5d 3a 20 53 70 65 63 69 66 79 20 61 6e 6f 74 68 65 72 20 70 6f 72 74 20 74 6f 20 63 6f 6e 6e 65 63 74 20 74 6f 2e 20 30 20 66 6f 72 20 6d 75 6c 74 69 70 6f 72 74 } //1 -p [PORT]: Specify another port to connect to. 0 for multiport
		$a_01_12 = {2d 63 20 5b 52 45 4d 4f 54 45 2d 43 4f 4d 4d 41 4e 44 5d 3a 20 43 6f 6d 6d 61 6e 64 20 74 6f 20 65 78 65 63 75 74 65 20 6f 6e 20 63 6f 6e 6e 65 63 74 2e 20 55 73 65 20 3b 20 6f 72 20 26 26 } //1 -c [REMOTE-COMMAND]: Command to execute on connect. Use ; or &&
		$a_01_13 = {55 73 65 3a 20 2e 2f 73 63 61 6e 20 2d 74 20 32 30 32 20 2d 73 20 35 20 2d 53 20 35 20 2d 69 20 30 20 2d 70 20 32 32 20 70 20 31 39 32 2e 31 36 38 } //1 Use: ./scan -t 202 -s 5 -S 5 -i 0 -p 22 p 192.168
		$a_01_14 = {68 6f 6e 65 79 70 6f 74 73 20 61 6e 64 20 6f 74 68 65 72 20 6c 69 6d 69 74 65 64 20 6c 69 6e 75 78 20 64 65 76 69 63 65 73 20 77 69 6c 6c 20 62 65 20 73 6b 69 70 70 65 64 20 66 72 6f 6d 20 74 68 65 20 6f 75 74 70 75 74 } //1 honeypots and other limited linux devices will be skipped from the output
		$a_01_15 = {66 69 6e 64 20 2e 2e 2f 2e 2e 2f 64 6f 74 61 33 2e 74 61 72 2e 67 7a 2e 20 50 72 6f 63 65 65 64 69 6e 67 20 77 69 74 68 6f 75 74 20 75 70 6c 6f 61 64 3a } //1 find ../../dota3.tar.gz. Proceeding without upload:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=5
 
}