
rule Worm_Win32_Pushbot_gen_C{
	meta:
		description = "Worm:Win32/Pushbot.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,2e 00 2b 00 32 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 64 6f 73 2e 73 79 6e } //01 00  ddos.syn
		$a_00_1 = {64 64 6f 73 2e 61 63 6b } //01 00  ddos.ack
		$a_00_2 = {64 64 6f 73 2e 72 61 6e 64 6f 6d } //01 00  ddos.random
		$a_00_3 = {2e 64 6f 77 6e 6c 6f 61 64 } //01 00  .download
		$a_02_4 = {2e 75 70 64 90 03 01 01 61 34 74 65 90 00 } //01 00 
		$a_00_5 = {6d 73 6e 2e 73 70 72 65 61 64 } //01 00  msn.spread
		$a_00_6 = {6d 73 6e 2e 6d 73 67 } //01 00  msn.msg
		$a_00_7 = {6d 73 6e 2e 73 74 61 74 73 } //01 00  msn.stats
		$a_00_8 = {6d 73 2e 73 74 61 74 73 } //01 00  ms.stats
		$a_00_9 = {73 63 61 6e 2e 73 74 6f 70 } //01 00  scan.stop
		$a_00_10 = {73 63 61 6e 2e 73 74 61 72 74 } //01 00  scan.start
		$a_00_11 = {62 6f 74 6b 69 6c 6c 65 72 2e 73 74 61 72 74 } //01 00  botkiller.start
		$a_00_12 = {61 69 6d 2e 6d 73 67 } //01 00  aim.msg
		$a_00_13 = {74 72 69 74 6f 6e 2e 6d 73 67 } //01 00  triton.msg
		$a_00_14 = {70 73 74 6f 72 65 2e 73 65 61 72 63 68 } //01 00  pstore.search
		$a_00_15 = {73 75 70 65 72 73 79 6e 2e 73 74 6f 70 } //01 00  supersyn.stop
		$a_00_16 = {64 6c 2e 73 74 61 72 74 } //01 00  dl.start
		$a_00_17 = {64 6c 2e 73 74 6f 70 } //01 00  dl.stop
		$a_00_18 = {6b 69 6c 6c 2e 62 6f 74 } //01 00  kill.bot
		$a_00_19 = {6d 73 6e 2e 73 70 61 6d } //01 00  msn.spam
		$a_00_20 = {6d 73 6e 2e 66 69 6c 65 } //01 00  msn.file
		$a_00_21 = {6d 73 6e 2e 73 74 6f 70 } //01 00  msn.stop
		$a_00_22 = {46 61 69 6c 65 64 20 74 6f 20 73 74 61 72 74 20 64 6c 20 74 68 72 65 61 64 2e } //01 00  Failed to start dl thread.
		$a_00_23 = {25 73 20 25 73 20 22 22 20 22 6c 6f 6c 22 20 3a 25 73 } //01 00  %s %s "" "lol" :%s
		$a_00_24 = {25 73 20 25 73 20 2a 20 30 20 3a 25 73 } //01 00  %s %s * 0 :%s
		$a_00_25 = {25 73 3a 2a 3a 45 6e 61 62 6c 65 64 3a 25 73 } //01 00  %s:*:Enabled:%s
		$a_00_26 = {6f 74 6f 20 3a 44 20 25 73 } //01 00  oto :D %s
		$a_02_27 = {5b 47 45 54 5d 3a 20 90 01 01 20 25 73 20 74 6f 3a 20 25 73 90 00 } //01 00 
		$a_02_28 = {46 69 6c 65 20 72 75 6e 6e 69 6e 67 3a 20 90 01 01 20 00 90 00 } //03 00 
		$a_01_29 = {6d 47 fe 74 e8 bf c2 45 90 35 d1 5e 33 0a 24 6d } //06 00 
		$a_00_30 = {5b 4d 73 6e 5d 3a 20 4d 65 73 73 61 67 65 20 73 65 6e 74 2e } //06 00  [Msn]: Message sent.
		$a_00_31 = {49 20 74 72 69 65 64 20 74 6f 20 66 6f 6f 6c 20 25 64 20 6d 6f 72 6f 6e 73 2e 00 } //06 00 
		$a_00_32 = {4d 73 6e 20 4d 65 73 73 61 67 65 20 73 65 6e 74 20 74 6f 20 25 64 20 6e 69 67 67 } //01 00  Msn Message sent to %d nigg
		$a_00_33 = {55 53 42 7c 25 73 7c 25 73 7c 25 73 7c 25 73 } //01 00  USB|%s|%s|%s|%s
		$a_00_34 = {53 75 70 65 72 73 79 6e 20 41 74 74 61 63 6b 20 41 63 74 69 76 65 21 } //01 00  Supersyn Attack Active!
		$a_00_35 = {4e 69 67 20 42 6f 74 20 76 } //06 00  Nig Bot v
		$a_00_36 = {54 53 6b 79 70 65 53 70 6c 69 74 74 65 72 00 00 54 43 6f 6e 76 65 72 73 61 74 69 6f 6e 73 43 6f 6e 74 72 6f 6c 00 00 00 41 54 4c 00 59 61 68 6f 6f 42 75 64 64 79 4d 61 69 6e } //02 00 
		$a_00_37 = {53 4b 59 50 45 2e 74 78 74 00 00 00 43 6c 6f 73 69 6e 67 20 49 4d 20 57 69 6e 64 6f 77 00 00 00 5f 5f 6f 78 46 72 61 6d 65 2e 63 6c 61 73 73 5f 5f } //01 00 
		$a_00_38 = {00 42 6c 61 73 74 20 49 4d 00 } //02 00  䈀慬瑳䤠M
		$a_03_39 = {5b 25 73 7c 25 73 5d 25 73 00 90 02 03 6e 5b 25 73 7c 25 73 5d 25 73 90 00 } //01 00 
		$a_01_40 = {61 73 73 20 6f 66 66 21 20 48 65 72 65 20 79 6f 75 20 67 6f 3a 20 68 74 74 70 3a } //01 00  ass off! Here you go: http:
		$a_01_41 = {25 73 5c 25 73 2e 65 78 65 00 } //01 00 
		$a_01_42 = {50 52 49 56 4d 53 47 00 } //01 00  剐噉卍G
		$a_01_43 = {2f 61 6a 61 78 2f 63 68 61 74 2f 62 75 64 64 79 5f 6c 69 73 74 2e 70 68 70 3f 5f 5f 61 3d 31 } //28 00  /ajax/chat/buddy_list.php?__a=1
		$a_03_44 = {56 6a 01 56 6a 11 ff d3 56 56 56 6a 56 90 01 06 50 ff d3 56 6a 03 6a 2d 6a 11 ff d3 90 00 } //28 00 
		$a_03_45 = {59 59 6a 00 6a 01 6a 00 6a 11 ff 15 90 01 04 6a 00 6a 00 6a 00 6a 56 ff 15 90 01 04 50 ff 15 90 01 04 6a 00 6a 03 6a 2d 6a 11 ff 15 90 01 04 90 03 10 11 83 bd 90 01 02 ff ff 00 75 90 01 01 6a 32 ff 15 6a 00 6a 00 6a 00 6a 0d ff 15 90 01 04 6a 32 ff 15 90 00 } //28 00 
		$a_03_46 = {56 6a 01 56 6a 11 ff d3 8b 3d 90 01 04 56 56 56 6a 56 ff d7 90 03 01 04 50 0f b6 c0 50 ff d3 56 6a 03 6a 2d 6a 11 ff d3 90 00 } //28 00 
		$a_03_47 = {6a 00 6a 01 6a 00 6a 11 90 03 05 04 ff 15 90 01 04 e8 90 01 05 6a 00 6a 00 6a 00 6a 56 90 03 05 04 ff 15 90 01 04 e8 90 01 05 50 90 03 05 04 ff 15 90 01 04 e8 90 01 05 6a 00 6a 03 6a 2d 6a 11 90 03 05 04 ff 15 90 01 04 e8 90 01 05 6a 00 6a 00 6a 00 6a 0d 90 00 } //28 00 
		$a_03_48 = {6a 00 6a 01 6a 00 6a 11 ff d6 6a 00 6a 00 6a 00 6a 56 ff 15 90 01 04 0f b6 d0 52 ff d6 6a 00 6a 03 6a 2d 6a 11 ff d6 6a 00 6a 00 6a 00 6a 0d ff d6 90 00 } //03 00 
		$a_01_49 = {3b d0 75 4f 8b 8d 00 fb ff ff 83 c1 01 89 8d 00 fb ff ff 8b 55 18 52 83 ec 34 b9 0d 00 00 00 8d b5 c4 fa ff ff } //00 00 
	condition:
		any of ($a_*)
 
}